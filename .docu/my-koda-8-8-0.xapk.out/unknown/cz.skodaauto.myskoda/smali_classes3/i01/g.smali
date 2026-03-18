.class public final Li01/g;
.super Ld01/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ljava/lang/String;

.field public final f:J

.field public final g:Lu01/b0;


# direct methods
.method public constructor <init>(Ljava/lang/String;JLu01/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li01/g;->e:Ljava/lang/String;

    .line 5
    .line 6
    iput-wide p2, p0, Li01/g;->f:J

    .line 7
    .line 8
    iput-object p4, p0, Li01/g;->g:Lu01/b0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b()J
    .locals 2

    .line 1
    iget-wide v0, p0, Li01/g;->f:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final d()Ld01/d0;
    .locals 1

    .line 1
    iget-object p0, p0, Li01/g;->e:Ljava/lang/String;

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
    iget-object p0, p0, Li01/g;->g:Lu01/b0;

    .line 2
    .line 3
    return-object p0
.end method
