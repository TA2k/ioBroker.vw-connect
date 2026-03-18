.class public abstract Lpa0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final b:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 5
    .line 6
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    sput-wide v0, Lpa0/a;->a:J

    .line 11
    .line 12
    new-instance v0, Lp81/c;

    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    invoke-direct {v0, v1}, Lp81/c;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Le21/a;

    .line 19
    .line 20
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lp81/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    sput-object v1, Lpa0/a;->b:Le21/a;

    .line 27
    .line 28
    return-void
.end method
