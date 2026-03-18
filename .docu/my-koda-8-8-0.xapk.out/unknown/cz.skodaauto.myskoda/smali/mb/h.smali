.class public final Lmb/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmb/h;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/16 v0, 0x14

    .line 9
    .line 10
    invoke-direct {p1, v0}, Las0/h;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lmb/h;->b:Las0/h;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public a(Lmb/i;)Lmb/f;
    .locals 3

    .line 1
    iget-object v0, p1, Lmb/i;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget p1, p1, Lmb/i;->b:I

    .line 4
    .line 5
    const-string v1, "workSpecId"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Lmb/g;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, v0, p1, v2}, Lmb/g;-><init>(Ljava/lang/String;II)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lmb/h;->a:Lla/u;

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-static {p0, p1, v0, v1}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lmb/f;

    .line 25
    .line 26
    return-object p0
.end method
