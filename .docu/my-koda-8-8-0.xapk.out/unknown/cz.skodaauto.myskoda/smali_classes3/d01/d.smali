.class public final Ld01/d;
.super Ld01/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lf01/d;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Lu01/b0;


# direct methods
.method public constructor <init>(Lf01/d;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld01/d;->e:Lf01/d;

    .line 5
    .line 6
    iput-object p2, p0, Ld01/d;->f:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ld01/d;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 p2, 0x1

    .line 11
    iget-object p1, p1, Lf01/d;->f:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lu01/h0;

    .line 18
    .line 19
    new-instance p2, Lbm/b;

    .line 20
    .line 21
    invoke-direct {p2, p1, p0}, Lbm/b;-><init>(Lu01/h0;Ld01/d;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p2}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Ld01/d;->h:Lu01/b0;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final b()J
    .locals 3

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    iget-object p0, p0, Ld01/d;->g:Ljava/lang/String;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sget-object v2, Le01/e;->a:[B

    .line 8
    .line 9
    :try_start_0
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    :catch_0
    :cond_0
    return-wide v0
.end method

.method public final d()Ld01/d0;
    .locals 1

    .line 1
    iget-object p0, p0, Ld01/d;->f:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 6
    .line 7
    invoke-static {p0}, Ljp/ue;->e(Ljava/lang/String;)Ld01/d0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final p0()Lu01/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/d;->h:Lu01/b0;

    .line 2
    .line 3
    return-object p0
.end method
