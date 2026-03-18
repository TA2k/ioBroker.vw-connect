.class public Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnet/zetetic/database/sqlcipher/SQLiteDebug;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "DbStats"
.end annotation


# instance fields
.field public cache:Ljava/lang/String;

.field public dbName:Ljava/lang/String;

.field public dbSize:J

.field public lookaside:I

.field public pageSize:J


# direct methods
.method public constructor <init>(Ljava/lang/String;JJIIII)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;->dbName:Ljava/lang/String;

    .line 5
    .line 6
    const-wide/16 v0, 0x400

    .line 7
    .line 8
    div-long v2, p4, v0

    .line 9
    .line 10
    iput-wide v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;->pageSize:J

    .line 11
    .line 12
    mul-long/2addr p2, p4

    .line 13
    div-long/2addr p2, v0

    .line 14
    iput-wide p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;->dbSize:J

    .line 15
    .line 16
    iput p6, p0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;->lookaside:I

    .line 17
    .line 18
    new-instance p1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, p7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string p2, "/"

    .line 27
    .line 28
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, p9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;->cache:Ljava/lang/String;

    .line 45
    .line 46
    return-void
.end method
