.class public abstract Lq21/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh21/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lh21/c;

    .line 2
    .line 3
    const-class v1, Landroidx/lifecycle/b1;

    .line 4
    .line 5
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 6
    .line 7
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1}, Lh21/c;-><init>(Lhy0/d;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lq21/a;->a:Lh21/c;

    .line 15
    .line 16
    return-void
.end method
