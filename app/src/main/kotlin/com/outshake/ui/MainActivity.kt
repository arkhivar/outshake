package com.outshake.ui

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.outshake.R
import com.outshake.config.Profile
import com.outshake.config.ProfileImporter
import com.outshake.databinding.ActivityMainBinding
import com.outshake.databinding.ItemProfileBinding
import com.outshake.shake.ShakeService
import com.outshake.store.ProfileStore
import com.outshake.vpn.ConnectionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var store: ProfileStore
    private lateinit var adapter: ProfileAdapter

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* best effort */ }

    private val vpnPrepare = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            store.activeProfile()?.let { ConnectionManager.connect(this, it.id) }
        } else {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        store = ProfileStore(this)

        adapter = ProfileAdapter()
        binding.profileList.layoutManager = LinearLayoutManager(this)
        binding.profileList.adapter = adapter

        binding.addButton.setOnClickListener { startActivity(Intent(this, ImportActivity::class.java)) }
        binding.settingsButton.setOnClickListener { startActivity(Intent(this, SettingsActivity::class.java)) }
        binding.toggleButton.setOnClickListener { onToggleClicked() }

        lifecycleScope.launch {
            ConnectionManager.state.collect { render(it) }
        }

        ensureNotificationPermission()
    }

    override fun onResume() {
        super.onResume()
        refreshProfiles()
        render(ConnectionManager.state.value)
        // Shake detection runs in a foreground service (works while backgrounded); start if enabled.
        ShakeService.sync(this)
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun onToggleClicked() {
        when (ConnectionManager.state.value) {
            ConnectionManager.State.CONNECTED -> ConnectionManager.disconnect(this)
            ConnectionManager.State.CONNECTING, ConnectionManager.State.DISCONNECTING -> {}
            else -> {
                val active = store.activeProfile()
                if (active == null) {
                    Toast.makeText(this, "Select or import a profile first", Toast.LENGTH_SHORT).show()
                    return
                }
                val prepare = VpnService.prepare(this)
                if (prepare != null) vpnPrepare.launch(prepare)
                else ConnectionManager.connect(this, active.id)
            }
        }
    }

    private fun refreshProfiles() {
        val profiles = store.getProfiles()
        adapter.submit(profiles, store.activeProfileId)
        binding.emptyText.visibility = if (profiles.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
        val active = store.activeProfile()
        binding.activeText.text = active?.let { "Active: ${it.name}" } ?: "No active profile"
    }

    private fun render(state: ConnectionManager.State) {
        binding.statusText.text = when (state) {
            ConnectionManager.State.DISCONNECTED -> "Disconnected"
            ConnectionManager.State.CONNECTING -> "Connecting…"
            ConnectionManager.State.CONNECTED -> "Connected"
            ConnectionManager.State.DISCONNECTING -> "Disconnecting…"
            ConnectionManager.State.ERROR -> "Error"
        }
        binding.toggleButton.text = when (state) {
            ConnectionManager.State.CONNECTED -> getString(R.string.disconnect)
            else -> getString(R.string.connect)
        }
        val err = ConnectionManager.lastError
        if (state == ConnectionManager.State.ERROR && err != null) {
            binding.errorText.visibility = android.view.View.VISIBLE
            binding.errorText.text = err
        } else {
            binding.errorText.visibility = android.view.View.GONE
        }
    }

    private inner class ProfileAdapter : RecyclerView.Adapter<ProfileAdapter.VH>() {
        private var items: List<Profile> = emptyList()
        private var activeId: String? = null

        fun submit(list: List<Profile>, activeId: String?) {
            this.items = list
            this.activeId = activeId
            notifyDataSetChanged()
        }

        inner class VH(val b: ItemProfileBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VH {
            val b = ItemProfileBinding.inflate(layoutInflater, parent, false)
            return VH(b)
        }

        override fun getItemCount() = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val p = items[position]
            holder.b.nameText.text = p.name
            val prefix = if (p.transport.prefix != null) " · prefix" else ""
            holder.b.detailText.text = "${p.sourceType.name.lowercase()} · ${p.transport.cipher.id}$prefix"
            holder.b.activeRadio.isChecked = p.id == activeId
            holder.b.refreshButton.visibility =
                if (p.sourceType == com.outshake.config.SourceType.DYNAMIC) android.view.View.VISIBLE
                else android.view.View.GONE

            holder.b.root.setOnClickListener {
                store.activeProfileId = p.id
                refreshProfiles()
            }
            holder.b.deleteButton.setOnClickListener {
                store.delete(p.id)
                refreshProfiles()
            }
            holder.b.refreshButton.setOnClickListener { refreshDynamic(p) }
        }
    }

    private fun refreshDynamic(profile: Profile) {
        Toast.makeText(this, "Refreshing…", Toast.LENGTH_SHORT).show()
        lifecycleScope.launch {
            try {
                val updated = withContext(Dispatchers.IO) { ProfileImporter.refresh(profile) }
                store.addOrUpdate(updated)
                refreshProfiles()
                Toast.makeText(this@MainActivity, "Updated ${updated.name}", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Refresh failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
}
