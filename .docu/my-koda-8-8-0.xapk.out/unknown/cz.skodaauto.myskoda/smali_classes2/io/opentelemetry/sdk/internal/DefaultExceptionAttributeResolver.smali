.class final Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;


# static fields
.field static final ENABLE_JVM_STACKTRACE_PROPERTY:Ljava/lang/String; = "otel.experimental.sdk.jvm_stacktrace"


# instance fields
.field private final jvmStacktraceEnabled:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;->jvmStacktraceEnabled:Z

    .line 5
    .line 6
    return-void
.end method

.method private static jvmStacktrace(Ljava/lang/Throwable;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/io/StringWriter;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/StringWriter;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/io/PrintWriter;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Ljava/io/PrintWriter;-><init>(Ljava/io/Writer;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-virtual {p0, v1}, Ljava/lang/Throwable;->printStackTrace(Ljava/io/PrintWriter;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/io/PrintWriter;->close()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    :try_start_1
    invoke-virtual {v1}, Ljava/io/PrintWriter;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_1
    move-exception v0

    .line 28
    invoke-virtual {p0, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    throw p0
.end method

.method private static limitsAwareStacktrace(Ljava/lang/Throwable;I)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/StackTraceRenderer;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;-><init>(Ljava/lang/Throwable;I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/StackTraceRenderer;->render()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method


# virtual methods
.method public setExceptionAttributes(Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;Ljava/lang/Throwable;I)V
    .locals 2

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    invoke-interface {p1, v1, v0}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-virtual {p2}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    sget-object v1, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_MESSAGE:Lio/opentelemetry/api/common/AttributeKey;

    .line 23
    .line 24
    invoke-interface {p1, v1, v0}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;->jvmStacktraceEnabled:Z

    .line 28
    .line 29
    if-eqz p0, :cond_2

    .line 30
    .line 31
    invoke-static {p2}, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;->jvmStacktrace(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p2, p3}, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;->limitsAwareStacktrace(Ljava/lang/Throwable;I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :goto_0
    sget-object p2, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_STACKTRACE:Lio/opentelemetry/api/common/AttributeKey;

    .line 41
    .line 42
    invoke-interface {p1, p2, p0}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method
