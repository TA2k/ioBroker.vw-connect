.class public final Lz1/e;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements Lv3/q;


# instance fields
.field public t:Le2/o0;

.field public final u:Ll2/j1;


# direct methods
.method public constructor <init>(Le2/o0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz1/e;->t:Le2/o0;

    .line 5
    .line 6
    sget-object p1, Ll2/x0;->f:Ll2/x0;

    .line 7
    .line 8
    new-instance v0, Ll2/j1;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lz1/e;->u:Ll2/j1;

    .line 15
    .line 16
    new-instance p1, Lb2/b;

    .line 17
    .line 18
    const/16 v0, 0xa

    .line 19
    .line 20
    invoke-direct {p1, p0, v0}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Lp3/f0;->a(Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lp3/j0;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p0, p1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 28
    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final K(Lv3/f1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lz1/e;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
