.class public final Lh2/v5;
.super Lb/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lvy0/b0;

.field public final c:Lc1/c;

.field public final d:Ld2/g;


# direct methods
.method public constructor <init>(ZLvy0/b0;Lc1/c;Ld2/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lb/a0;-><init>(Z)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lh2/v5;->b:Lvy0/b0;

    .line 5
    .line 6
    iput-object p3, p0, Lh2/v5;->c:Lc1/c;

    .line 7
    .line 8
    iput-object p4, p0, Lh2/v5;->d:Ld2/g;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final handleOnBackCancelled()V
    .locals 3

    .line 1
    new-instance v0, Ldm0/h;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, v2, v1}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    iget-object p0, p0, Lh2/v5;->b:Lvy0/b0;

    .line 11
    .line 12
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final handleOnBackPressed()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/v5;->d:Ld2/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld2/g;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final handleOnBackProgressed(Lb/c;)V
    .locals 3

    .line 1
    new-instance v0, Lh2/u5;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, p1, v2, v1}, Lh2/u5;-><init>(Lh2/v5;Lb/c;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x3

    .line 9
    iget-object p0, p0, Lh2/v5;->b:Lvy0/b0;

    .line 10
    .line 11
    invoke-static {p0, v2, v2, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final handleOnBackStarted(Lb/c;)V
    .locals 3

    .line 1
    new-instance v0, Lh2/u5;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, p1, v2, v1}, Lh2/u5;-><init>(Lh2/v5;Lb/c;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x3

    .line 9
    iget-object p0, p0, Lh2/v5;->b:Lvy0/b0;

    .line 10
    .line 11
    invoke-static {p0, v2, v2, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 12
    .line 13
    .line 14
    return-void
.end method
