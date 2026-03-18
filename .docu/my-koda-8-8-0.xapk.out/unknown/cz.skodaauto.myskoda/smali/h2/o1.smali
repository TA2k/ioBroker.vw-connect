.class public final Lh2/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# static fields
.field public static final d:Lh2/o1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/o1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/o1;->d:Lh2/o1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-wide v0, Le3/s;->b:J

    .line 2
    .line 3
    new-instance p0, Le3/s;

    .line 4
    .line 5
    invoke-direct {p0, v0, v1}, Le3/s;-><init>(J)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method
