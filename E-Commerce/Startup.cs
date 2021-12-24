using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using E_Commerce.Models.Identity;
using E_Commerce.Data;
using E_Commerce.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using E_Commerce.Services.Identity;
using Microsoft.Extensions.Azure;
using Azure.Storage.Queues;
using Azure.Storage.Blobs;
using Azure.Core.Extensions;
using Microsoft.OpenApi.Models;

namespace E_Commerce
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices ( IServiceCollection services )
        {
            services.AddControllersWithViews();
            services.AddRazorPages();
            services.AddDbContext<ECommerceDbContext>(options =>
             options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
            services.AddSession();
            services.AddMvc();


            //Identity!!
            services
                .AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ECommerceDbContext>();  //where are users stored?

            services.AddScoped<IUserService, IdentityUserService>();
            //end of Identity

            services.AddScoped<IProductCategoryRepository, DatabaseProductCategoryRepository>();
            services.AddScoped<IProductRepository, DatabaseProductRepository>();
            services.AddScoped<IDashboardRepository, DashboardRepository>();
            services.AddSingleton<IFileUploadService, AzureFileUploadService>();
            services.AddSingleton<IEmailService, SendGridEmailService>();
            services.AddAzureClients(builder =>
            {
                builder.AddBlobServiceClient(Configuration["AzureStorageAccountName:blob"], preferMsi: true);
                builder.AddQueueServiceClient(Configuration["AzureStorageAccountName:queue"], preferMsi: true);
            });
            services.AddSwaggerGen(options =>
            {
                //make sure  to get the "using statement"
                options.SwaggerDoc("v1", new OpenApiInfo()
                {
                    Title = "ECommerce",
                    Version = "v1",
                });
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            // else
            // {
            //      app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            // }

            app.UseSwagger(options =>
            {
                options.RouteTemplate = "/api/{documentName}/swagger.json";
            });

            app.UseSwaggerUI(options => {
                options.SwaggerEndpoint("/api/v1/swagger.json", "ECommerce");
                options.RoutePrefix = "docs";
            });

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSession();
            //app.UseMvc();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                //First check to see if there is a Razor Page - order of endpoints matter
                //endpoints.MapRazorPages();
                //Used this for APIs, which specify their own routes
                endpoints.MapControllers();

                endpoints.MapGet("/", async context =>
                {
                    context.Response.Redirect("/docs");
                });
                //Default route "convention"
       //         endpoints.MapControllerRoute(
        //            name: "default",
        //            pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
    internal static class StartupExtensions
    {
        public static IAzureClientBuilder<BlobServiceClient, BlobClientOptions> AddBlobServiceClient ( this AzureClientFactoryBuilder builder, string serviceUriOrConnectionString, bool preferMsi )
        {
            if (preferMsi && Uri.TryCreate(serviceUriOrConnectionString, UriKind.Absolute, out Uri serviceUri))
            {
                return builder.AddBlobServiceClient(serviceUri);
            }
            else
            {
                return builder.AddBlobServiceClient(serviceUriOrConnectionString);
            }
        }
        public static IAzureClientBuilder<QueueServiceClient, QueueClientOptions> AddQueueServiceClient ( this AzureClientFactoryBuilder builder, string serviceUriOrConnectionString, bool preferMsi )
        {
            if (preferMsi && Uri.TryCreate(serviceUriOrConnectionString, UriKind.Absolute, out Uri serviceUri))
            {
                return builder.AddQueueServiceClient(serviceUri);
            }
            else
            {
                return builder.AddQueueServiceClient(serviceUriOrConnectionString);
            }
        }
    }
}
