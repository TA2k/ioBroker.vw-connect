.class public abstract Lzg/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation

.annotation runtime Lvz0/j;
    discriminator = "infrastructureType"
.end annotation


# static fields
.field public static final Companion:Lzg/p0;

.field public static final a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lzg/p0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzg/w0;->Companion:Lzg/p0;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lz81/g;

    .line 11
    .line 12
    const/16 v2, 0x11

    .line 13
    .line 14
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lzg/w0;->a:Ljava/lang/Object;

    .line 22
    .line 23
    return-void
.end method
