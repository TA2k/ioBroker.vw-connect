.class public abstract Lgv0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Leo0/b;

.field public static final b:Leo0/b;

.field public static final c:Ly40/b;

.field public static final d:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Leo0/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const-string v2, "maps_section_map"

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lgv0/b;->a:Leo0/b;

    .line 10
    .line 11
    new-instance v0, Leo0/b;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v2, v1}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lgv0/b;->b:Leo0/b;

    .line 18
    .line 19
    new-instance v0, Ly40/b;

    .line 20
    .line 21
    invoke-direct {v0, v2}, Ly40/b;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lgv0/b;->c:Ly40/b;

    .line 25
    .line 26
    new-instance v0, Lg4/a0;

    .line 27
    .line 28
    const/16 v1, 0x1c

    .line 29
    .line 30
    invoke-direct {v0, v1}, Lg4/a0;-><init>(I)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Le21/a;

    .line 34
    .line 35
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v1}, Lg4/a0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    sput-object v1, Lgv0/b;->d:Le21/a;

    .line 42
    .line 43
    return-void
.end method
