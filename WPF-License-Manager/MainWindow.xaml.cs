/*
 * This code is a ported and modifyed from VB.NET-License-Manager. https://github.com/fdeitelhoff/VB.NET-License-Manager
 * 
 * Copyright © 2014 Pasi J. Elo
 * Author:
 * Pasi J. Elo        blackdogspark@hotmail.com
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace WPF_License_Manager
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Text;
    using System.Windows;
    using System.Windows.Controls;

    using Microsoft.Win32;

    using Portable.Licensing;
    using Portable.Licensing.Validation;

    using License = Portable.Licensing.License;

    /// <summary>
    /// Interaction logic for MainWindow.
    /// </summary>
    public partial class MainWindow
    {
        /// <summary>
        /// The license object.
        /// </summary>
        private License ulicense;

        /// <summary>
        /// The private key.
        /// </summary>
        private string privateKey;

        /// <summary>
        /// The public key.
        /// </summary>
        private string publicKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// The license exception.
        /// </summary>
        /// <param name="license">
        /// The license.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        private static bool LicenseException(License license)
        {
            //// check licensetype.
            return license.Type == LicenseType.Trial;
        }

        /// <summary>
        /// The button create keys click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ButtonCreateKeysClick(object sender, RoutedEventArgs e)
        {
            /*
                1. define a KeyGenerator and a KeyPair.
                2. split the KeyPair into the private key (encoded with the password) and public key.
            */
            var keyGenerator = Portable.Licensing.Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();

            this.privateKey = keyPair.ToEncryptedPrivateKeyString(TextBoxPassword.Text.Trim());
            this.publicKey = keyPair.ToPublicKeyString();
            this.TextBoxKey.Text = this.publicKey;
            ButtonCreateLic.IsEnabled = true;
        }

        /// <summary>
        /// The button create license click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ButtonCreateLicClick(object sender, RoutedEventArgs e)
        {
            /*
                1. define a new Dictionary for the addition attributes and add the attributes.
                2. define a new Dictionary for the product features and add the features.
                3. create new guid as unique identifier.
                4. define the license with the required parameters.
                5. select Path and filename to write the license.
            */

            var attributesDictionarty = new Dictionary<string, string>
            {
                {
                    this.TextBoxAttributeName.Text,
                    this.TextBoxAttributeValue.Text
                }
            };

            var productFeatureDictionarty = new Dictionary<string, string>
            {
                {
                    "Sales",
                    this.CheckBoxSales.IsChecked.ToString()
                },
                {
                    "Billing", this.CheckBoxBilling.IsChecked.ToString() 
                } 
            };

            var licenseId = Guid.NewGuid();

            var datetime = DatePickerExpiration.SelectedDate;

            if (datetime != null)
            {
                this.ulicense =
                    License.New().WithUniqueIdentifier(licenseId)
                        .As(this.GetLicenseType())
                        .WithMaximumUtilization(int.Parse(this.TextBoxUsers.Text))
                        .WithAdditionalAttributes(attributesDictionarty)
                        .WithProductFeatures(productFeatureDictionarty)
                        .LicensedTo(this.TextBoxCustomer.Text, this.TextBoxEMail.Text)
                        .ExpiresAt(datetime.Value.AddDays(int.Parse(TextBoxDays.Text)))
                        .CreateAndSignWithPrivateKey(this.privateKey, this.TextBoxPassword.Text);
            }

            var sfdlicense = new SaveFileDialog
            {
                Filter = "License (*.lic)|*.lic",
                FilterIndex = 1,
                RestoreDirectory = true,
                FileName = "lic",
                InitialDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
            };
            var result = sfdlicense.ShowDialog();
            if (result.HasValue && result.Value)
            {
                var sw = new StreamWriter(sfdlicense.FileName, false, Encoding.UTF8);
                sw.Write(this.ulicense.ToString());
                sw.Close();
                sw.Dispose();
            }

            ButtonOpenLic.IsEnabled = true;

            TestApp.IsEnabled = true;
        }

        /// <summary>
        /// The button open license click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ButtonOpenLicClick(object sender, RoutedEventArgs e)
        {
            /*
                1. clear validation listbox.
                2. define a new stream and select and read the license.
                3. read the values from the license.
                4. validate the license (expiration date and signature).
             */
            ListBoxValidation.Items.Clear();

            var ofdlicense = new OpenFileDialog();
            ////Dim LicStreamReader As StreamReader
            Stream myStream = null;

            ////OfDLicense.InitialDirectory = "c:\"
            ofdlicense.Filter = "License (*.lic)|*.lic";
            ofdlicense.FilterIndex = 1;
            ofdlicense.InitialDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            var result = ofdlicense.ShowDialog();
            if (!result.HasValue || !result.Value)
            {
                return;
            }

            try
            {
                myStream = ofdlicense.OpenFile();
                if (myStream.Length <= 0)
                {
                    return;
                }

                this.ulicense = License.Load(myStream);
                this.TextBoxCustomerRo.Text = this.ulicense.Customer.Name;
                this.TextBoxEMailRo.Text = this.ulicense.Customer.Email;
                this.TextBoxUsersRo.Text = this.ulicense.Quantity.ToString(CultureInfo.InvariantCulture);
                this.TextBoxAttributeNameRo.Text = "Software";
                this.TextBoxAttributeValueRo.Text = this.ulicense.AdditionalAttributes.Get(this.TextBoxAttributeNameRo.Text);
                this.CheckBoxSalesRo.IsChecked = this.ulicense.ProductFeatures.Get("Sales") == "True";
                this.CheckBoxBillingRo.IsChecked = this.ulicense.ProductFeatures.Get("Billing") == "True";
                this.TextBoxLicenseType.Text = this.ulicense.Type.ToString();
                var str = this.ValidateLicense(this.ulicense);
                var lbi = new ListBoxItem { Content = str };
                this.ListBoxValidation.Items.Add(lbi);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Cannot read file from disk. Original error: " + ex.Message);
            }
            finally
            {
                //// Check this again, since we need to make sure we didn't throw an exception on open.
                if (myStream != null)
                {
                    myStream.Close();
                }
            }
        }

        /// <summary>
        /// The get license type.
        /// </summary>
        /// <returns>
        /// The <see cref="LicenseType"/>.
        /// </returns>
        private LicenseType GetLicenseType()
        {
            return this.ComboBoxLicenseType.Text == "Trial" ? LicenseType.Trial : LicenseType.Standard;
        }

        /// <summary>
        /// The validate license.
        /// </summary>
        /// <param name="license">
        /// The license.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private string ValidateLicense(License license)
        {
            //// validate license and define return value.
            const string ReturnValue = "License is Valid";

            var validationFailures =
                license.Validate()
                    .ExpirationDate()
                    .When(LicenseException)
                    .And()
                    .Signature(this.publicKey)
                    .AssertValidLicense();

            var failures = validationFailures as IValidationFailure[] ?? validationFailures.ToArray();

            return !failures.Any() ? ReturnValue : failures.Aggregate(string.Empty, (current, validationFailure) => current + validationFailure.HowToResolve + ": " + "\r\n" + validationFailure.Message + "\r\n");
        }

        /// <summary>
        /// The button click.
        /// </summary>
        /// <param name="sender">
        /// The sender.
        /// </param>
        /// <param name="e">
        /// The e.
        /// </param>
        private void ButtonClick(object sender, RoutedEventArgs e)
        {
            var path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\ClientSample.exe";
            try
            {
                Process.Start(path);
            }
            catch (Exception ee)
            {
                Debug.Print(ee.Message);
                MessageBox.Show(
                    "Could not open directory '" + path + "'",
                    "Directory Error!",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
