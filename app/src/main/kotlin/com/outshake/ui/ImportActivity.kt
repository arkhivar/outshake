package com.outshake.ui

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.outshake.config.ProfileImporter
import com.outshake.databinding.ActivityImportBinding
import com.outshake.store.ProfileStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ImportActivity : AppCompatActivity() {

    private lateinit var binding: ActivityImportBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityImportBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.importButton.setOnClickListener { doImport() }
    }

    private fun doImport() {
        val key = binding.keyInput.text.toString().trim()
        if (key.isEmpty()) {
            binding.messageText.text = "Enter an ss:// or ssconf:// key"
            return
        }
        binding.progress.visibility = View.VISIBLE
        binding.messageText.text = ""
        binding.importButton.isEnabled = false

        lifecycleScope.launch {
            try {
                val profile = withContext(Dispatchers.IO) { ProfileImporter.import(key) }
                val store = ProfileStore(this@ImportActivity)
                store.addOrUpdate(profile)
                if (store.activeProfileId == null) store.activeProfileId = profile.id
                finish()
            } catch (e: Exception) {
                binding.progress.visibility = View.GONE
                binding.importButton.isEnabled = true
                binding.messageText.text = e.message ?: "Import failed"
            }
        }
    }
}
