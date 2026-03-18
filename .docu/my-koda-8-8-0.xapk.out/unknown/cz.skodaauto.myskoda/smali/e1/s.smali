.class public final Le1/s;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/x1;


# instance fields
.field public t:Le1/o;

.field public u:F

.field public v:Le3/p0;

.field public w:Le3/n0;

.field public final x:Lb3/c;


# direct methods
.method public constructor <init>(FLe3/p0;Le3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Le1/s;->u:F

    .line 5
    .line 6
    iput-object p2, p0, Le1/s;->v:Le3/p0;

    .line 7
    .line 8
    iput-object p3, p0, Le1/s;->w:Le3/n0;

    .line 9
    .line 10
    new-instance p1, La2/e;

    .line 11
    .line 12
    const/16 p2, 0x18

    .line 13
    .line 14
    invoke-direct {p1, p0, p2}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    new-instance p2, Lb3/c;

    .line 18
    .line 19
    new-instance p3, Lb3/d;

    .line 20
    .line 21
    invoke-direct {p3}, Lb3/d;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-direct {p2, p3, p1}, Lb3/c;-><init>(Lb3/d;Lay0/k;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p2}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 28
    .line 29
    .line 30
    iput-object p2, p0, Le1/s;->x:Lb3/c;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final a0(Ld4/l;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
