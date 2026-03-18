.class public final Lj3/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Le3/f;

.field public b:Le3/a;

.field public c:J

.field public d:I

.field public final e:Lg3/b;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    iput-wide v0, p0, Lj3/a;->c:J

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput v0, p0, Lj3/a;->d:I

    .line 12
    .line 13
    new-instance v0, Lg3/b;

    .line 14
    .line 15
    invoke-direct {v0}, Lg3/b;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lj3/a;->e:Lg3/b;

    .line 19
    .line 20
    return-void
.end method
