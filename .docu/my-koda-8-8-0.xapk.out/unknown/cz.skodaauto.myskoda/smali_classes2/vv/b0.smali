.class public abstract Lvv/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/a1;

.field public static final b:Lvv/a0;

.field public static final c:Lvv/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    new-instance v1, Lk1/a1;

    .line 5
    .line 6
    invoke-direct {v1, v0, v0, v0, v0}, Lk1/a1;-><init>(FFFF)V

    .line 7
    .line 8
    .line 9
    sput-object v1, Lvv/b0;->a:Lk1/a1;

    .line 10
    .line 11
    sget-object v0, Lvv/a0;->g:Lvv/a0;

    .line 12
    .line 13
    sput-object v0, Lvv/b0;->b:Lvv/a0;

    .line 14
    .line 15
    sget-object v0, Lvv/a0;->h:Lvv/a0;

    .line 16
    .line 17
    sput-object v0, Lvv/b0;->c:Lvv/a0;

    .line 18
    .line 19
    return-void
.end method
