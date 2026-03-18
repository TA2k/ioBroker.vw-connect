.class public final Lez0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/k;
.implements Lvy0/k2;


# instance fields
.field public final d:Lvy0/l;

.field public final synthetic e:Lez0/c;


# direct methods
.method public constructor <init>(Lez0/c;Lvy0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lez0/b;->e:Lez0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lez0/b;->d:Lvy0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Laz0/q;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lvy0/l;->b(Laz0/q;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Ljava/lang/Throwable;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final getContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 2
    .line 3
    iget-object p0, p0, Lvy0/l;->h:Lpx0/g;

    .line 4
    .line 5
    return-object p0
.end method

.method public final h(Ljava/lang/Object;Lay0/o;)Lj51/i;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    new-instance p2, Lb50/c;

    .line 4
    .line 5
    iget-object v0, p0, Lez0/b;->e:Lez0/c;

    .line 6
    .line 7
    invoke-direct {p2, v0, p0}, Lb50/c;-><init>(Lez0/c;Lez0/b;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2}, Lvy0/l;->F(Ljava/lang/Object;Lay0/o;)Lj51/i;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    sget-object p1, Lez0/c;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-virtual {p1, v0, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-object p0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final t(Ljava/lang/Object;Lay0/o;)V
    .locals 2

    .line 1
    sget-object p1, Lez0/c;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    const/4 p2, 0x0

    .line 4
    iget-object v0, p0, Lez0/b;->e:Lez0/c;

    .line 5
    .line 6
    invoke-virtual {p1, v0, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    new-instance p1, Le81/w;

    .line 10
    .line 11
    invoke-direct {p1, v0, p0}, Le81/w;-><init>(Lez0/c;Lez0/b;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 15
    .line 16
    iget p2, p0, Lvy0/n0;->f:I

    .line 17
    .line 18
    new-instance v0, Lkv0/d;

    .line 19
    .line 20
    const/16 v1, 0xd

    .line 21
    .line 22
    invoke-direct {v0, p1, v1}, Lkv0/d;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2, v0}, Lvy0/l;->C(Ljava/lang/Object;ILay0/o;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public final w(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lez0/b;->d:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lvy0/l;->w(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
