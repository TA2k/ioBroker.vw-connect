.class public abstract Lgz0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final b:J

.field public static final synthetic c:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Ljava/time/LocalDate;->MIN:Ljava/time/LocalDate;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    sput-wide v0, Lgz0/t;->a:J

    .line 8
    .line 9
    sget-object v0, Ljava/time/LocalDate;->MAX:Ljava/time/LocalDate;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/time/LocalDate;->toEpochDay()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    sput-wide v0, Lgz0/t;->b:J

    .line 16
    .line 17
    return-void
.end method
