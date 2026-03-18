.class public final Lvp/r2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:J

.field public d:Z

.field public final e:Z

.field public final f:J


# direct methods
.method public constructor <init>(JLjava/lang/String;Ljava/lang/String;)V
    .locals 8

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    move-object v0, p0

    move-wide v3, p1

    move-object v1, p3

    move-object v2, p4

    .line 2
    invoke-direct/range {v0 .. v7}, Lvp/r2;-><init>(Ljava/lang/String;Ljava/lang/String;JZJ)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;JZJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/r2;->a:Ljava/lang/String;

    iput-object p2, p0, Lvp/r2;->b:Ljava/lang/String;

    iput-wide p3, p0, Lvp/r2;->c:J

    const/4 p1, 0x0

    iput-boolean p1, p0, Lvp/r2;->d:Z

    iput-boolean p5, p0, Lvp/r2;->e:Z

    iput-wide p6, p0, Lvp/r2;->f:J

    return-void
.end method
