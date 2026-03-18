.class public abstract Ltw/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltw/e;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltw/b;

    .line 2
    .line 3
    const/16 v1, 0x64

    .line 4
    .line 5
    sget-object v2, Ltw/j;->a:Ltw/j;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Ltw/b;-><init>(ILtw/e;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Ltw/b;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    sget-object v2, Ltw/k;->b:Ltw/k;

    .line 14
    .line 15
    invoke-direct {v0, v1, v2}, Ltw/b;-><init>(ILtw/e;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Ltw/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw/c;->a:Ltw/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public abstract a(FF)F
.end method
