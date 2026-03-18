.class public final Lp1/b;
.super Lp1/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final J:Lu2/l;


# instance fields
.field public final I:Ll2/j1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lo90/a;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lo90/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lod0/g;

    .line 9
    .line 10
    const/16 v2, 0x13

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lod0/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lu2/m;->b(Lay0/n;Lay0/k;)Lu2/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lp1/b;->J:Lu2/l;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(IFLay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lp1/v;-><init>(IF)V

    .line 2
    .line 3
    .line 4
    invoke-static {p3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lp1/b;->I:Ll2/j1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final m()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/b;->I:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lay0/a;

    .line 8
    .line 9
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method
