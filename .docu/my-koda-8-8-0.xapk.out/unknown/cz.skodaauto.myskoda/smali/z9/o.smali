.class public abstract Lz9/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lp7/d;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lfb/k;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, Lfb/k;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lz70/e0;

    .line 8
    .line 9
    const/4 v2, 0x4

    .line 10
    invoke-direct {v1, v2}, Lz70/e0;-><init>(I)V

    .line 11
    .line 12
    .line 13
    const-class v2, Lz9/n;

    .line 14
    .line 15
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0, v2, v1}, Lfb/k;->b(Lhy0/d;Lay0/k;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lfb/k;->d()Lp7/d;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lz9/o;->a:Lp7/d;

    .line 29
    .line 30
    return-void
.end method
