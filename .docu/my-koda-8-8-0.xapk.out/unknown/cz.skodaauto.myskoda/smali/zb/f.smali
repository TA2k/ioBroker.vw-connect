.class public final Lzb/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/a;

.field public final b:Lay0/a;

.field public final c:Lay0/a;


# direct methods
.method public constructor <init>(Lay0/a;Lay0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lz81/g;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "expandBottomSheet"

    .line 8
    .line 9
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "collapseBottomSheet"

    .line 13
    .line 14
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lzb/f;->a:Lay0/a;

    .line 21
    .line 22
    iput-object p2, p0, Lzb/f;->b:Lay0/a;

    .line 23
    .line 24
    iput-object v0, p0, Lzb/f;->c:Lay0/a;

    .line 25
    .line 26
    return-void
.end method
