.class public abstract Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;,
        Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;,
        Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;,
        Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Data:",
        "Ljava/lang/Object;",
        "Error:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00087\u0018\u0000*\n\u0008\u0000\u0010\u0002 \u0001*\u00020\u0001*\n\u0008\u0001\u0010\u0003 \u0001*\u00020\u00012\u00020\u0001:\u0004\r\u000e\u000f\u0010B\t\u0008\u0004\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u001b\u0010\t\u001a\u00020\u00068FX\u0086\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\nR\u001b\u0010\u000c\u001a\u00020\u00068FX\u0086\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008\u000b\u0010\u0008\u001a\u0004\u0008\u000c\u0010\n\u0082\u0001\u0004\u0011\u0012\u0013\u0014\u00a8\u0006\u0015"
    }
    d2 = {
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "",
        "Data",
        "Error",
        "<init>",
        "()V",
        "",
        "isSuccess$delegate",
        "Llx0/i;",
        "isSuccess",
        "()Z",
        "isError$delegate",
        "isError",
        "Success",
        "ApiError",
        "NetworkError",
        "UnknownError",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$NetworkError;",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$UnknownError;",
        "lib-retrofit-adapter_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final isError$delegate:Llx0/i;

.field private final isSuccess$delegate:Llx0/i;


# direct methods
.method private constructor <init>()V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Lji/c;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lji/c;-><init>(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;I)V

    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object v0

    iput-object v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isSuccess$delegate:Llx0/i;

    .line 4
    new-instance v0, Lji/c;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lji/c;-><init>(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;I)V

    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object v0

    iput-object v0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isError$delegate:Llx0/i;

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;-><init>()V

    return-void
.end method

.method public static synthetic a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isSuccess_delegate$lambda$0(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isError_delegate$lambda$0(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final isError_delegate$lambda$0(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z
    .locals 0

    .line 1
    instance-of p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method

.method private static final isSuccess_delegate$lambda$0(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Z
    .locals 0

    .line 1
    instance-of p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$Success;

    .line 2
    .line 3
    return p0
.end method


# virtual methods
.method public final isError()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isError$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final isSuccess()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;->isSuccess$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
