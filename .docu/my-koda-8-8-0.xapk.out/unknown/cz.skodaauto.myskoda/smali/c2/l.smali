.class public final Lc2/l;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements Lv3/q;
.implements Lv3/m;


# instance fields
.field public r:Lc2/b;

.field public s:Lt1/p0;

.field public t:Le2/w0;

.field public final u:Ll2/j1;


# direct methods
.method public constructor <init>(Lc2/b;Lt1/p0;Le2/w0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc2/l;->r:Lc2/b;

    .line 5
    .line 6
    iput-object p2, p0, Lc2/l;->s:Lt1/p0;

    .line 7
    .line 8
    iput-object p3, p0, Lc2/l;->t:Le2/w0;

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lc2/l;->u:Ll2/j1;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final K(Lv3/f1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/l;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final P0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lc2/l;->r:Lc2/b;

    .line 2
    .line 3
    iget-object v1, v0, Lc2/b;->a:Lc2/l;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const-string v1, "Expected textInputModifierNode to be null"

    .line 9
    .line 10
    invoke-static {v1}, Lj1/b;->c(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    :goto_0
    iput-object p0, v0, Lc2/b;->a:Lc2/l;

    .line 14
    .line 15
    return-void
.end method

.method public final Q0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lc2/l;->r:Lc2/b;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lc2/b;->k(Lc2/l;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
