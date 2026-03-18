.class public abstract Lmo0/b;
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
    const/16 v0, 0xa

    .line 4
    .line 5
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sput-wide v0, Lmo0/b;->a:J

    .line 12
    .line 13
    new-instance v0, Lmj/g;

    .line 14
    .line 15
    const/4 v1, 0x5

    .line 16
    invoke-direct {v0, v1}, Lmj/g;-><init>(I)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Le21/a;

    .line 20
    .line 21
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lmj/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    sput-object v1, Lmo0/b;->b:Le21/a;

    .line 28
    .line 29
    return-void
.end method
