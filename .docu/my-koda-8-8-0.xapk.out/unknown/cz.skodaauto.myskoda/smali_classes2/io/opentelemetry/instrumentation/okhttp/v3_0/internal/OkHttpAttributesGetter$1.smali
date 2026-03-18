.class synthetic Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1009
    name = null
.end annotation


# static fields
.field static final synthetic $SwitchMap$okhttp3$Protocol:[I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    invoke-static {}, Ld01/i0;->values()[Ld01/i0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    sput-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    sget-object v2, Ld01/i0;->e:Ld01/r;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    :catch_0
    const/4 v0, 0x2

    .line 17
    :try_start_1
    sget-object v2, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    .line 18
    .line 19
    sget-object v3, Ld01/i0;->e:Ld01/r;

    .line 20
    .line 21
    aput v0, v2, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 22
    .line 23
    :catch_1
    :try_start_2
    sget-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    .line 24
    .line 25
    sget-object v2, Ld01/i0;->e:Ld01/r;

    .line 26
    .line 27
    const/4 v2, 0x3

    .line 28
    aput v2, v1, v2
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 29
    .line 30
    :catch_2
    :try_start_3
    sget-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    .line 31
    .line 32
    sget-object v2, Ld01/i0;->e:Ld01/r;

    .line 33
    .line 34
    const/4 v2, 0x4

    .line 35
    aput v2, v1, v0
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 36
    .line 37
    :catch_3
    return-void
.end method
