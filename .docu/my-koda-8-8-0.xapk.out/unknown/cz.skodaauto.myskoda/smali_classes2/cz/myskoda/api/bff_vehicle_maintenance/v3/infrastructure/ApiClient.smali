.class public final Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000n\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0011\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u001c\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0010%\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u000e\u0018\u0000 H2\u00020\u0001:\u0001HBS\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\n\u0008\u0002\u0010\t\u001a\u0004\u0018\u00010\u0008\u0012\u000e\u0008\u0002\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\n\u0012\u000e\u0008\u0002\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\n\u00a2\u0006\u0004\u0008\u000f\u0010\u0010B7\u0008\u0016\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\u000c\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u0011\u00a2\u0006\u0004\u0008\u000f\u0010\u0013B9\u0008\u0016\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\u0014\u001a\u00020\u0002\u0012\u0006\u0010\u0015\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u000f\u0010\u0016J\u000f\u0010\u0018\u001a\u00020\u0017H\u0002\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J<\u0010\u001f\u001a\u00020\u0017\"\u0004\u0008\u0000\u0010\u001a\"\u0006\u0008\u0001\u0010\u001b\u0018\u0001*\u0008\u0012\u0004\u0012\u00028\u00000\u001c2\u0012\u0010\u001e\u001a\u000e\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00020\u00170\u001dH\u0082\u0008\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0015\u0010!\u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u0002\u00a2\u0006\u0004\u0008!\u0010\"J\u001d\u0010%\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u00022\u0006\u0010$\u001a\u00020#\u00a2\u0006\u0004\u0008%\u0010&J!\u0010(\u001a\u00020\u00002\u0012\u0010\'\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00170\u001d\u00a2\u0006\u0004\u0008(\u0010)J!\u0010-\u001a\u00028\u0000\"\u0004\u0008\u0000\u0010*2\u000c\u0010,\u001a\u0008\u0012\u0004\u0012\u00028\u00000+\u00a2\u0006\u0004\u0008-\u0010.R\u0016\u0010\u0003\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010/R\u0016\u0010\u0005\u001a\u0004\u0018\u00010\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u00100R\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u00101R\u0016\u0010\t\u001a\u0004\u0018\u00010\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u00102R\u001a\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\n8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u00103R\u001a\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\n8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u00103R \u00105\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020#048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00085\u00106R0\u0010\'\u001a\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0017\u0018\u00010\u001d8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\'\u00107\u001a\u0004\u00088\u00109\"\u0004\u0008(\u0010:R\u001b\u0010@\u001a\u00020;8BX\u0082\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008<\u0010=\u001a\u0004\u0008>\u0010?R\u001b\u0010D\u001a\u00020\u00048BX\u0082\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008A\u0010=\u001a\u0004\u0008B\u0010CR\u001b\u0010G\u001a\u00020\u00048BX\u0082\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008E\u0010=\u001a\u0004\u0008F\u0010C\u00a8\u0006I"
    }
    d2 = {
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;",
        "",
        "",
        "baseUrl",
        "Ld01/g0;",
        "okHttpClientBuilder",
        "Lcom/squareup/moshi/Moshi$Builder;",
        "serializerBuilder",
        "Ld01/i;",
        "callFactory",
        "",
        "Lretrofit2/CallAdapter$Factory;",
        "callAdapterFactories",
        "Lretrofit2/Converter$Factory;",
        "converterFactories",
        "<init>",
        "(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;)V",
        "",
        "authNames",
        "(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;[Ljava/lang/String;)V",
        "authName",
        "bearerToken",
        "(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Ljava/lang/String;)V",
        "Llx0/b0;",
        "normalizeBaseUrl",
        "()V",
        "T",
        "U",
        "",
        "Lkotlin/Function1;",
        "callback",
        "runOnFirst",
        "(Ljava/lang/Iterable;Lay0/k;)V",
        "setBearerToken",
        "(Ljava/lang/String;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;",
        "Ld01/c0;",
        "authorization",
        "addAuthorization",
        "(Ljava/lang/String;Ld01/c0;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;",
        "logger",
        "setLogger",
        "(Lay0/k;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;",
        "S",
        "Ljava/lang/Class;",
        "serviceClass",
        "createService",
        "(Ljava/lang/Class;)Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ld01/g0;",
        "Lcom/squareup/moshi/Moshi$Builder;",
        "Ld01/i;",
        "Ljava/util/List;",
        "",
        "apiAuthorizations",
        "Ljava/util/Map;",
        "Lay0/k;",
        "getLogger",
        "()Lay0/k;",
        "(Lay0/k;)V",
        "Lretrofit2/Retrofit$Builder;",
        "retrofitBuilder$delegate",
        "Llx0/i;",
        "getRetrofitBuilder",
        "()Lretrofit2/Retrofit$Builder;",
        "retrofitBuilder",
        "clientBuilder$delegate",
        "getClientBuilder",
        "()Ld01/g0;",
        "clientBuilder",
        "defaultClientBuilder$delegate",
        "getDefaultClientBuilder",
        "defaultClientBuilder",
        "Companion",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

.field private static final baseUrlKey:Ljava/lang/String;

.field private static final defaultBasePath$delegate:Llx0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llx0/i;"
        }
    .end annotation
.end field


# instance fields
.field private final apiAuthorizations:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ld01/c0;",
            ">;"
        }
    .end annotation
.end field

.field private baseUrl:Ljava/lang/String;

.field private final callAdapterFactories:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lretrofit2/CallAdapter$Factory;",
            ">;"
        }
    .end annotation
.end field

.field private final callFactory:Ld01/i;

.field private final clientBuilder$delegate:Llx0/i;

.field private final converterFactories:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lretrofit2/Converter$Factory;",
            ">;"
        }
    .end annotation
.end field

.field private final defaultClientBuilder$delegate:Llx0/i;

.field private logger:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private final okHttpClientBuilder:Ld01/g0;

.field private final retrofitBuilder$delegate:Llx0/i;

.field private final serializerBuilder:Lcom/squareup/moshi/Moshi$Builder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    .line 8
    .line 9
    const-string v0, "cz.myskoda.api.bff_vehicle_maintenance.v3.baseUrl"

    .line 10
    .line 11
    sput-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrlKey:Ljava/lang/String;

    .line 12
    .line 13
    new-instance v0, Ldc/a;

    .line 14
    .line 15
    const/16 v1, 0xc

    .line 16
    .line 17
    invoke-direct {v0, v1}, Ldc/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultBasePath$delegate:Llx0/i;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>()V
    .locals 9

    .line 1
    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ld01/g0;",
            "Lcom/squareup/moshi/Moshi$Builder;",
            "Ld01/i;",
            "Ljava/util/List<",
            "+",
            "Lretrofit2/CallAdapter$Factory;",
            ">;",
            "Ljava/util/List<",
            "+",
            "Lretrofit2/Converter$Factory;",
            ">;)V"
        }
    .end annotation

    const-string v0, "baseUrl"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "serializerBuilder"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callAdapterFactories"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "converterFactories"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrl:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->okHttpClientBuilder:Ld01/g0;

    .line 5
    iput-object p3, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->serializerBuilder:Lcom/squareup/moshi/Moshi$Builder;

    .line 6
    iput-object p4, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->callFactory:Ld01/i;

    .line 7
    iput-object p5, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->callAdapterFactories:Ljava/util/List;

    .line 8
    iput-object p6, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->converterFactories:Ljava/util/List;

    .line 9
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->apiAuthorizations:Ljava/util/Map;

    .line 10
    new-instance p1, Ldy/a;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Ldy/a;-><init>(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;I)V

    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object p1

    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->retrofitBuilder$delegate:Llx0/i;

    .line 11
    new-instance p1, Ldy/a;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Ldy/a;-><init>(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;I)V

    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object p1

    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->clientBuilder$delegate:Llx0/i;

    .line 12
    new-instance p1, Ldy/a;

    const/4 p2, 0x2

    invoke-direct {p1, p0, p2}, Ldy/a;-><init>(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;I)V

    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object p1

    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultClientBuilder$delegate:Llx0/i;

    .line 13
    invoke-direct {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->normalizeBaseUrl()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p8, p7, 0x1

    if-eqz p8, :cond_0

    .line 14
    sget-object p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;->getDefaultBasePath()Ljava/lang/String;

    move-result-object p1

    :cond_0
    and-int/lit8 p8, p7, 0x2

    const/4 v0, 0x0

    if-eqz p8, :cond_1

    move-object p2, v0

    :cond_1
    and-int/lit8 p8, p7, 0x4

    if-eqz p8, :cond_2

    .line 15
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/Serializer;->getMoshiBuilder()Lcom/squareup/moshi/Moshi$Builder;

    move-result-object p3

    :cond_2
    and-int/lit8 p8, p7, 0x8

    if-eqz p8, :cond_3

    move-object p4, v0

    :cond_3
    and-int/lit8 p8, p7, 0x10

    if-eqz p8, :cond_4

    .line 16
    sget-object p5, Lmx0/s;->d:Lmx0/s;

    :cond_4
    and-int/lit8 p7, p7, 0x20

    if-eqz p7, :cond_5

    .line 17
    invoke-static {}, Lretrofit2/converter/scalars/ScalarsConverterFactory;->c()Lretrofit2/converter/scalars/ScalarsConverterFactory;

    move-result-object p6

    .line 18
    invoke-static {p3, p3}, Lkx/a;->c(Lcom/squareup/moshi/Moshi$Builder;Lcom/squareup/moshi/Moshi$Builder;)Lcom/squareup/moshi/Moshi;

    move-result-object p7

    .line 19
    new-instance p8, Lretrofit2/converter/moshi/MoshiConverterFactory;

    invoke-direct {p8, p7}, Lretrofit2/converter/moshi/MoshiConverterFactory;-><init>(Lcom/squareup/moshi/Moshi;)V

    const/4 p7, 0x2

    .line 20
    new-array p7, p7, [Lretrofit2/Converter$Factory;

    const/4 v0, 0x0

    aput-object p6, p7, v0

    const/4 p6, 0x1

    aput-object p8, p7, p6

    .line 21
    invoke-static {p7}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p6

    :cond_5
    move-object p7, p5

    move-object p8, p6

    move-object p5, p3

    move-object p6, p4

    move-object p3, p1

    move-object p4, p2

    move-object p2, p0

    .line 22
    invoke-direct/range {p2 .. p8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "baseUrl"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "serializerBuilder"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "authName"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bearerToken"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    filled-new-array {p4}, [Ljava/lang/String;

    move-result-object p4

    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;[Ljava/lang/String;)V

    .line 45
    invoke-virtual {p0, p5}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->setBearerToken(Ljava/lang/String;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p7, p6, 0x1

    if-eqz p7, :cond_0

    .line 41
    sget-object p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;->getDefaultBasePath()Ljava/lang/String;

    move-result-object p1

    :cond_0
    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_1

    const/4 p2, 0x0

    :cond_1
    and-int/lit8 p6, p6, 0x4

    if-eqz p6, :cond_2

    .line 42
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/Serializer;->getMoshiBuilder()Lcom/squareup/moshi/Moshi$Builder;

    move-result-object p3

    :cond_2
    move-object p6, p4

    move-object p7, p5

    move-object p4, p2

    move-object p5, p3

    move-object p2, p0

    move-object p3, p1

    .line 43
    invoke-direct/range {p2 .. p7}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;[Ljava/lang/String;)V
    .locals 10

    const-string v0, "baseUrl"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "serializerBuilder"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "authNames"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v8, 0x38

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 29
    invoke-direct/range {v1 .. v9}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;Ld01/i;Ljava/util/List;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 30
    array-length p0, p4

    const/4 p1, 0x0

    :goto_0
    if-ge p1, p0, :cond_1

    aget-object p2, p4, p1

    .line 31
    const-string p3, "bearerAuth"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    new-instance p3, Lcz/myskoda/api/bff_vehicle_maintenance/v3/auth/HttpBearerAuth;

    const-string v0, "bearer"

    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-direct {p3, v0, v3, v2, v3}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/auth/HttpBearerAuth;-><init>(Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V

    .line 32
    invoke-virtual {v1, p2, p3}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->addAuthorization(Ljava/lang/String;Ld01/c0;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;

    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    const-string p1, "auth name "

    const-string p3, " not found in available auth names"

    .line 34
    invoke-static {p1, p2, p3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 35
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;[Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p6, p5, 0x1

    if-eqz p6, :cond_0

    .line 26
    sget-object p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    invoke-virtual {p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;->getDefaultBasePath()Ljava/lang/String;

    move-result-object p1

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    const/4 p2, 0x0

    :cond_1
    and-int/lit8 p5, p5, 0x4

    if-eqz p5, :cond_2

    .line 27
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/Serializer;->getMoshiBuilder()Lcom/squareup/moshi/Moshi$Builder;

    move-result-object p3

    .line 28
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;-><init>(Ljava/lang/String;Ld01/g0;Lcom/squareup/moshi/Moshi$Builder;[Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic a(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;
    .locals 0

    .line 1
    invoke-static {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultClientBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getBaseUrlKey$cp()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrlKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getDefaultBasePath$delegate$cp()Llx0/i;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultBasePath$delegate:Llx0/i;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic b(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultClientBuilder_delegate$lambda$0$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultBasePath_delegate$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final clientBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;
    .locals 1

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->okHttpClientBuilder:Ld01/g0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-direct {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->getDefaultClientBuilder()Ld01/g0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    return-object v0
.end method

.method public static synthetic d(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;
    .locals 0

    .line 1
    invoke-static {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->clientBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final defaultBasePath_delegate$lambda$0()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {}, Ljava/lang/System;->getProperties()Ljava/util/Properties;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrlKey:Ljava/lang/String;

    .line 6
    .line 7
    const-string v2, "https://mysmob.dev-api.connect.skoda-auto.cz"

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2}, Ljava/util/Properties;->getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method private static final defaultClientBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Ld01/g0;
    .locals 4

    .line 1
    invoke-static {}, Lkx/a;->d()Ld01/g0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lt01/c;

    .line 6
    .line 7
    new-instance v2, La8/t;

    .line 8
    .line 9
    const/16 v3, 0x16

    .line 10
    .line 11
    invoke-direct {v2, p0, v3}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v2}, Lt01/c;-><init>(Lt01/b;)V

    .line 15
    .line 16
    .line 17
    sget-object p0, Lt01/a;->f:Lt01/a;

    .line 18
    .line 19
    iput-object p0, v1, Lt01/c;->b:Lt01/a;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ld01/g0;->a(Ld01/c0;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method private static final defaultClientBuilder_delegate$lambda$0$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->logger:Lay0/k;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public static synthetic e(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Lretrofit2/Retrofit$Builder;
    .locals 0

    .line 1
    invoke-static {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->retrofitBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Lretrofit2/Retrofit$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final getBaseUrlKey()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;->getBaseUrlKey()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method private final getClientBuilder()Ld01/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->clientBuilder$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld01/g0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static final getDefaultBasePath()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->Companion:Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient$Companion;->getDefaultBasePath()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method private final getDefaultClientBuilder()Ld01/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->defaultClientBuilder$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld01/g0;

    .line 8
    .line 9
    return-object p0
.end method

.method private final getRetrofitBuilder()Lretrofit2/Retrofit$Builder;
    .locals 1

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->retrofitBuilder$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "getValue(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast p0, Lretrofit2/Retrofit$Builder;

    .line 13
    .line 14
    return-object p0
.end method

.method private final normalizeBaseUrl()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrl:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "/"

    .line 5
    .line 6
    invoke-static {v0, v2, v1}, Lly0/w;->o(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrl:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrl:Ljava/lang/String;

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method private static final retrofitBuilder_delegate$lambda$0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;)Lretrofit2/Retrofit$Builder;
    .locals 3

    .line 1
    new-instance v0, Lretrofit2/Retrofit$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Lretrofit2/Retrofit$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->baseUrl:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit$Builder;->c(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->callAdapterFactories:Ljava/util/List;

    .line 12
    .line 13
    check-cast v1, Ljava/lang/Iterable;

    .line 14
    .line 15
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lretrofit2/CallAdapter$Factory;

    .line 30
    .line 31
    invoke-virtual {v0, v2}, Lretrofit2/Retrofit$Builder;->a(Lretrofit2/CallAdapter$Factory;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->converterFactories:Ljava/util/List;

    .line 36
    .line 37
    check-cast p0, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Lretrofit2/Converter$Factory;

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit$Builder;->b(Lretrofit2/Converter$Factory;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    return-object v0
.end method

.method private final synthetic runOnFirst(Ljava/lang/Iterable;Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Iterable<",
            "+TT;>;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    invoke-static {}, Lkotlin/jvm/internal/m;->k()V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    throw p0
.end method


# virtual methods
.method public final addAuthorization(Ljava/lang/String;Ld01/c0;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;
    .locals 1

    .line 1
    const-string v0, "authName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "authorization"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->apiAuthorizations:Ljava/util/Map;

    .line 12
    .line 13
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->apiAuthorizations:Ljava/util/Map;

    .line 20
    .line 21
    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    invoke-direct {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->getClientBuilder()Ld01/g0;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p1, p2}, Ld01/g0;->a(Ld01/c0;)V

    .line 29
    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 33
    .line 34
    const-string p2, "auth name "

    .line 35
    .line 36
    const-string v0, " already in api authorizations"

    .line 37
    .line 38
    invoke-static {p2, p1, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method public final createService(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<S:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Class<",
            "TS;>;)TS;"
        }
    .end annotation

    .line 1
    const-string v0, "serviceClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->callFactory:Ld01/i;

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    invoke-direct {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->getClientBuilder()Ld01/g0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {v0, v0}, Lkx/a;->e(Ld01/g0;Ld01/g0;)Ld01/h0;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_0
    invoke-direct {p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->getRetrofitBuilder()Lretrofit2/Retrofit$Builder;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lretrofit2/Retrofit$Builder;->a:Ld01/i;

    .line 26
    .line 27
    invoke-virtual {p0}, Lretrofit2/Retrofit$Builder;->d()Lretrofit2/Retrofit;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0, p1}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public final getLogger()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->logger:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setBearerToken(Ljava/lang/String;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;
    .locals 3

    .line 1
    const-string v0, "bearerToken"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->apiAuthorizations:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Ljava/lang/Iterable;

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    instance-of v2, v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/auth/HttpBearerAuth;

    .line 29
    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/auth/HttpBearerAuth;

    .line 33
    .line 34
    invoke-virtual {v1, p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/auth/HttpBearerAuth;->setBearerToken(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    return-object p0
.end method

.method public final setLogger(Lay0/k;)Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;"
        }
    .end annotation

    const-string v0, "logger"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->logger:Lay0/k;

    return-object p0
.end method

.method public final setLogger(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->logger:Lay0/k;

    return-void
.end method
