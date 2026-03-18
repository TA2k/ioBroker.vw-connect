.class public final Luu/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luu/d;


# instance fields
.field public final synthetic a:Lvy0/l;

.field public final synthetic b:Luu/g;

.field public final synthetic c:Lpv/g;

.field public final synthetic d:I


# direct methods
.method public constructor <init>(Lvy0/l;Luu/g;Lpv/g;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/f;->a:Lvy0/l;

    .line 5
    .line 6
    iput-object p2, p0, Luu/f;->b:Luu/g;

    .line 7
    .line 8
    iput-object p3, p0, Luu/f;->c:Lpv/g;

    .line 9
    .line 10
    iput p4, p0, Luu/f;->d:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/concurrent/CancellationException;

    .line 2
    .line 3
    const-string v1, "Animation cancelled"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Luu/f;->a:Lvy0/l;

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final b(Lqp/g;)V
    .locals 3

    .line 1
    iget-object v0, p0, Luu/f;->a:Lvy0/l;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Luu/f;->c:Lpv/g;

    .line 6
    .line 7
    iget v2, p0, Luu/f;->d:I

    .line 8
    .line 9
    iget-object p0, p0, Luu/f;->b:Luu/g;

    .line 10
    .line 11
    invoke-static {p0, p1, v1, v2, v0}, Luu/g;->a(Luu/g;Lqp/g;Lpv/g;ILvy0/l;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 16
    .line 17
    const-string p1, "internal error; no GoogleMap available"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {v0, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "internal error; no GoogleMap available to animate position"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method
