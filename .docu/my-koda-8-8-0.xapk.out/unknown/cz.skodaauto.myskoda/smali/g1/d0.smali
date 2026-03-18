.class public final Lg1/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/j1;


# instance fields
.field public a:Lc1/u;

.field public final b:Lg1/g2;


# direct methods
.method public constructor <init>(Lc1/u;)V
    .locals 1

    .line 1
    sget-object v0, Landroidx/compose/foundation/gestures/b;->c:Lg1/g2;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lg1/d0;->a:Lc1/u;

    .line 7
    .line 8
    iput-object v0, p0, Lg1/d0;->b:Lg1/g2;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lg1/e2;FLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lg1/c0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p2, p0, p1, v1}, Lg1/c0;-><init>(FLg1/d0;Lg1/e2;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lg1/d0;->b:Lg1/g2;

    .line 8
    .line 9
    invoke-static {p0, v0, p3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
