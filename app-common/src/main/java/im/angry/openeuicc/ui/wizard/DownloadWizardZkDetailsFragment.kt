package im.angry.openeuicc.ui.wizard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.core.widget.addTextChangedListener
import com.google.android.material.textfield.TextInputLayout
import im.angry.openeuicc.common.R

class DownloadWizardZkDetailsFragment : DownloadWizardActivity.DownloadWizardStepFragment() {
    private var inputComplete = false

    override val hasNext: Boolean
        get() = inputComplete
    override val hasPrev: Boolean
        get() = true

    private val mnoAddress: EditText by lazy {
        requireView().requireViewById<TextInputLayout>(R.id.profile_download_zk_mno).editText!!
    }
    private val pcaAddress: EditText by lazy {
        requireView().requireViewById<TextInputLayout>(R.id.profile_download_zk_pca).editText!!
    }
    private val confirmationCode: EditText by lazy {
        requireView().requireViewById<TextInputLayout>(R.id.profile_download_zk_confirmation_code).editText!!
    }

    private fun saveState() {
        state.mnoAddress = mnoAddress.text.toString().trim()
        state.pcaAddress = pcaAddress.text.toString().trim()
        state.confirmationCode = confirmationCode.text.toString().trim().ifBlank { null }
    }

    override fun beforeNext() = saveState()

    override fun createNextFragment(): DownloadWizardActivity.DownloadWizardStepFragment =
        DownloadWizardProgressFragment()

    override fun createPrevFragment(): DownloadWizardActivity.DownloadWizardStepFragment =
        DownloadWizardMethodSelectFragment()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View =
        inflater.inflate(R.layout.fragment_download_zk_details, container, /* attachToRoot = */ false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        mnoAddress.addTextChangedListener { updateInputCompleteness() }
        pcaAddress.addTextChangedListener { updateInputCompleteness() }
    }

    override fun onStart() {
        super.onStart()
        mnoAddress.setText(state.mnoAddress)
        pcaAddress.setText(state.pcaAddress)
        confirmationCode.setText(state.confirmationCode)
        updateInputCompleteness()
    }

    override fun onPause() {
        super.onPause()
        saveState()
    }

    private fun updateInputCompleteness() {
        inputComplete = mnoAddress.text.isNotBlank() && pcaAddress.text.isNotBlank()
        refreshButtons()
    }
}