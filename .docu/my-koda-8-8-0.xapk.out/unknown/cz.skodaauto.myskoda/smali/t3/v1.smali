.class public final Lt3/v1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/u1;


# instance fields
.field public final b:Ljava/lang/String;

.field public final c:Lt3/r;

.field public final d:Lt3/r;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/v1;->b:Ljava/lang/String;

    .line 5
    .line 6
    new-instance v0, Lt3/r;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lt3/r;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lt3/v1;->c:Lt3/r;

    .line 12
    .line 13
    const-string v0, " maximum"

    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance v0, Lt3/r;

    .line 20
    .line 21
    invoke-direct {v0, p1}, Lt3/r;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lt3/v1;->d:Lt3/r;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/v1;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
