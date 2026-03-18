.class final Lretrofit2/KotlinExtensions$suspendAndThrow$1;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Lrx0/e;
    c = "retrofit2.KotlinExtensions"
    f = "KotlinExtensions.kt"
    l = {
        0x77
    }
    m = "suspendAndThrow"
.end annotation


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public e:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-static {p1, p0}, Lretrofit2/KotlinExtensions;->c(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    return-object p0
.end method
