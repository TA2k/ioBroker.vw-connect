.class public final Lt0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/b0;


# instance fields
.field public final d:Lh0/b0;

.field public final e:Lh0/b;

.field public final f:Lt0/i;

.field public final g:Lt0/h;


# direct methods
.method public constructor <init>(Lh0/b0;Lt0/h;Lt0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt0/g;->d:Lh0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lt0/g;->g:Lt0/h;

    .line 7
    .line 8
    new-instance p2, Lh0/b;

    .line 9
    .line 10
    invoke-interface {p1}, Lh0/b0;->g()Lh0/y;

    .line 11
    .line 12
    .line 13
    move-result-object p3

    .line 14
    invoke-direct {p2, p3}, Lh0/b;-><init>(Lh0/y;)V

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Lt0/g;->e:Lh0/b;

    .line 18
    .line 19
    new-instance p2, Lt0/i;

    .line 20
    .line 21
    invoke-interface {p1}, Lh0/b0;->l()Lh0/z;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-direct {p2, p1}, Lt0/i;-><init>(Lh0/z;)V

    .line 26
    .line 27
    .line 28
    iput-object p2, p0, Lt0/g;->f:Lt0/i;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final b()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "Operation not supported by VirtualCamera."

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final c()Lh0/m1;
    .locals 0

    .line 1
    iget-object p0, p0, Lt0/g;->d:Lh0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh0/b0;->c()Lh0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final e(Lb0/z1;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lt0/g;->g:Lt0/h;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lt0/h;->e(Lb0/z1;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final f(Lb0/z1;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lt0/g;->g:Lt0/h;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lt0/h;->f(Lb0/z1;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final g()Lh0/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lt0/g;->e:Lh0/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(Ljava/util/Collection;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "Operation not supported by VirtualCamera."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final l()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lt0/g;->f:Lt0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(Lb0/z1;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lt0/g;->g:Lt0/h;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lt0/h;->m(Lb0/z1;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final o(Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "Operation not supported by VirtualCamera."

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final p()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final r(Lb0/z1;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lt0/g;->g:Lt0/h;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lt0/h;->r(Lb0/z1;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
