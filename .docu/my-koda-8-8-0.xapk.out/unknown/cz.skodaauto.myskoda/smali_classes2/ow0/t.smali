.class public abstract Low0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Low0/s;->b:Low0/s;

    .line 2
    .line 3
    sget-object v1, Low0/s;->d:Low0/s;

    .line 4
    .line 5
    sget-object v2, Low0/s;->e:Low0/s;

    .line 6
    .line 7
    new-instance v3, Low0/s;

    .line 8
    .line 9
    const-string v4, "TRACE"

    .line 10
    .line 11
    invoke-direct {v3, v4}, Low0/s;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    filled-new-array {v0, v1, v2, v3}, [Low0/s;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Low0/t;->a:Ljava/util/Set;

    .line 23
    .line 24
    return-void
.end method
