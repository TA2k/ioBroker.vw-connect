.class public abstract Lzk0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Leo0/b;

.field public static final b:Leo0/b;

.field public static final c:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Leo0/b;

    .line 2
    .line 3
    const-string v1, "select_from_map"

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lzk0/b;->a:Leo0/b;

    .line 10
    .line 11
    new-instance v0, Leo0/b;

    .line 12
    .line 13
    const-string v1, "maps_section_map"

    .line 14
    .line 15
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lzk0/b;->b:Leo0/b;

    .line 19
    .line 20
    new-instance v0, Lz70/e0;

    .line 21
    .line 22
    const/16 v1, 0x16

    .line 23
    .line 24
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 25
    .line 26
    .line 27
    new-instance v1, Le21/a;

    .line 28
    .line 29
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lz70/e0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sput-object v1, Lzk0/b;->c:Le21/a;

    .line 36
    .line 37
    return-void
.end method
