.class public abstract Le2/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Le2/d1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ldc/a;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldc/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Le2/e1;->a:Ll2/e0;

    .line 14
    .line 15
    const-wide v0, 0xff4286f4L

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    new-instance v2, Le2/d1;

    .line 25
    .line 26
    const v3, 0x3ecccccd    # 0.4f

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v1, v3}, Le3/s;->b(JF)J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    invoke-direct {v2, v0, v1, v3, v4}, Le2/d1;-><init>(JJ)V

    .line 34
    .line 35
    .line 36
    sput-object v2, Le2/e1;->b:Le2/d1;

    .line 37
    .line 38
    return-void
.end method
