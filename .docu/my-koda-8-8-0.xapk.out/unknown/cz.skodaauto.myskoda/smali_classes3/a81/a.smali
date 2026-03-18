.class public abstract La81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final b:J

.field public static final synthetic c:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 4
    .line 5
    const/16 v1, 0x1e

    .line 6
    .line 7
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    sput-wide v2, La81/a;->a:J

    .line 12
    .line 13
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 14
    .line 15
    .line 16
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 17
    .line 18
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    sput-wide v0, La81/a;->b:J

    .line 23
    .line 24
    return-void
.end method
