.class public abstract Lph0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final b:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    sget-object v0, Lmy0/e;->j:Lmy0/e;

    .line 4
    .line 5
    const/16 v1, 0xc

    .line 6
    .line 7
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    sput-wide v1, Lph0/b;->a:J

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 15
    .line 16
    .line 17
    new-instance v0, Lp81/c;

    .line 18
    .line 19
    const/16 v1, 0xa

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lp81/c;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Le21/a;

    .line 25
    .line 26
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v1}, Lp81/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    sput-object v1, Lph0/b;->b:Le21/a;

    .line 33
    .line 34
    return-void
.end method
