.class public abstract Lz80/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Leo0/b;

.field public static final b:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Leo0/b;

    .line 2
    .line 3
    const-string v1, "test_drive_player"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lz80/b;->a:Leo0/b;

    .line 10
    .line 11
    new-instance v0, Lz70/e0;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Le21/a;

    .line 18
    .line 19
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lz70/e0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    sput-object v1, Lz80/b;->b:Le21/a;

    .line 26
    .line 27
    return-void
.end method
