.class public abstract Lfk0/a;
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
    const-string v1, "maps_section_map"

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lfk0/a;->a:Leo0/b;

    .line 10
    .line 11
    new-instance v0, Lf31/n;

    .line 12
    .line 13
    const/16 v1, 0xa

    .line 14
    .line 15
    invoke-direct {v0, v1}, Lf31/n;-><init>(I)V

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
    invoke-virtual {v0, v1}, Lf31/n;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    sput-object v1, Lfk0/a;->b:Le21/a;

    .line 27
    .line 28
    return-void
.end method
