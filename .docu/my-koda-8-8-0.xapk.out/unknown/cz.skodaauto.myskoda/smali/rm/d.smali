.class public final Lrm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lrm/f;


# instance fields
.field public final a:Lzl/i;

.field public final b:Lmm/j;


# direct methods
.method public constructor <init>(Lzl/i;Lmm/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrm/d;->a:Lzl/i;

    .line 5
    .line 6
    iput-object p2, p0, Lrm/d;->b:Lmm/j;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lrm/d;->b:Lmm/j;

    .line 2
    .line 3
    instance-of v1, v0, Lmm/p;

    .line 4
    .line 5
    iget-object p0, p0, Lrm/d;->a:Lzl/i;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    check-cast v0, Lmm/p;

    .line 10
    .line 11
    iget-object v0, v0, Lmm/p;->a:Lyl/j;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    instance-of v1, v0, Lmm/c;

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    check-cast v0, Lmm/c;

    .line 22
    .line 23
    iget-object v0, v0, Lmm/c;->a:Lyl/j;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    new-instance p0, La8/r0;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0
.end method
