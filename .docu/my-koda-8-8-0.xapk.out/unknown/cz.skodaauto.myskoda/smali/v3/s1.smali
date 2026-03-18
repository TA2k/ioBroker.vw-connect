.class public final Lv3/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p1;


# instance fields
.field public d:Lt3/r0;

.field public final e:Lv3/p0;


# direct methods
.method public constructor <init>(Lt3/r0;Lv3/p0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/s1;->d:Lt3/r0;

    .line 5
    .line 6
    iput-object p2, p0, Lv3/s1;->e:Lv3/p0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final e0()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/s1;->e:Lv3/p0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/p0;->J0()Lt3/y;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Lt3/y;->g()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
