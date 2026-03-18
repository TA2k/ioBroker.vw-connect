.class public final Lkf0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/z;


# direct methods
.method public constructor <init>(Lkf0/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/v;->a:Lkf0/z;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lkf0/v;->a:Lkf0/z;

    .line 2
    .line 3
    invoke-virtual {p0}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyy0/i;

    .line 8
    .line 9
    new-instance v0, Ljy/b;

    .line 10
    .line 11
    const/16 v1, 0x18

    .line 12
    .line 13
    invoke-direct {v0, v1}, Ljy/b;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0, v0}, Lbb/j0;->b(Lyy0/i;Lay0/k;)Lne0/k;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
