.class public final Lc1/n0;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ll2/j1;

.field public final g:Ll2/j1;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lc1/n0;->f:Ll2/j1;

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lc1/n0;->g:Ll2/j1;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final D()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/n0;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final F()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/n0;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final T(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/n0;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final V(Lc1/w1;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final W()V
    .locals 0

    .line 1
    return-void
.end method

.method public final b0(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/n0;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
