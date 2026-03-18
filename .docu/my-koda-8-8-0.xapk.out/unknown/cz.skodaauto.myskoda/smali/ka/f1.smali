.class public final Lka/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:La5/e;


# instance fields
.field public a:I

.field public b:Lb8/i;

.field public c:Lb8/i;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, La5/e;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, La5/e;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lka/f1;->d:La5/e;

    .line 9
    .line 10
    return-void
.end method

.method public static a()Lka/f1;
    .locals 1

    .line 1
    sget-object v0, Lka/f1;->d:La5/e;

    .line 2
    .line 3
    invoke-virtual {v0}, La5/e;->a()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lka/f1;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Lka/f1;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-object v0
.end method
