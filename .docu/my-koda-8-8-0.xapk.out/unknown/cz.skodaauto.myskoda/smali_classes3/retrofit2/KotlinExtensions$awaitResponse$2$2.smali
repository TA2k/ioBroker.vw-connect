.class public final Lretrofit2/KotlinExtensions$awaitResponse$2$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Callback;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lretrofit2/Callback<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\n\u0018\u00002\u0008\u0012\u0004\u0012\u00028\u00000\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "retrofit2/KotlinExtensions$awaitResponse$2$2",
        "Lretrofit2/Callback;",
        "retrofit"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final synthetic d:Lvy0/l;


# direct methods
.method public constructor <init>(Lvy0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/KotlinExtensions$awaitResponse$2$2;->d:Lvy0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/Call;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    const-string p1, "t"

    .line 2
    .line 3
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lretrofit2/KotlinExtensions$awaitResponse$2$2;->d:Lvy0/l;

    .line 7
    .line 8
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final b(Lretrofit2/Call;Lretrofit2/Response;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/KotlinExtensions$awaitResponse$2$2;->d:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
