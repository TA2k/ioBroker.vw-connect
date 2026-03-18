.class public interface abstract Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public addLogRecordExporterCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/logs/export/LogRecordExporter;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/logs/export/LogRecordExporter;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addLogRecordProcessorCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/logs/LogRecordProcessor;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/logs/LogRecordProcessor;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addLoggerProviderCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "Lio/opentelemetry/sdk/logs/SdkLoggerProviderBuilder;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addMeterProviderCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "Lio/opentelemetry/sdk/metrics/SdkMeterProviderBuilder;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addMetricExporterCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/metrics/export/MetricExporter;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/metrics/export/MetricExporter;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addMetricReaderCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/metrics/export/MetricReader;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/metrics/export/MetricReader;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public abstract addPropagatorCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/context/propagation/TextMapPropagator;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/context/propagation/TextMapPropagator;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation
.end method

.method public addPropertiesCustomizer(Ljava/util/function/Function;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public abstract addPropertiesSupplier(Ljava/util/function/Supplier;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation
.end method

.method public abstract addResourceCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/resources/Resource;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation
.end method

.method public abstract addSamplerCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/trace/samplers/Sampler;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/trace/samplers/Sampler;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation
.end method

.method public abstract addSpanExporterCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/trace/export/SpanExporter;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/trace/export/SpanExporter;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation
.end method

.method public addSpanProcessorCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "-",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "+",
            "Lio/opentelemetry/sdk/trace/SpanProcessor;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public addTracerProviderCustomizer(Ljava/util/function/BiFunction;)Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiFunction<",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;",
            "Lio/opentelemetry/sdk/autoconfigure/spi/ConfigProperties;",
            "Lio/opentelemetry/sdk/trace/SdkTracerProviderBuilder;",
            ">;)",
            "Lio/opentelemetry/sdk/autoconfigure/spi/AutoConfigurationCustomizer;"
        }
    .end annotation

    .line 1
    return-object p0
.end method
