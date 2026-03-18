.class public final Lky0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;


# instance fields
.field public final a:Lky0/j;

.field public final b:Lay0/k;


# direct methods
.method public constructor <init>(Lky0/j;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "sequence"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "transformer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lky0/s;->a:Lky0/j;

    .line 15
    .line 16
    iput-object p2, p0, Lky0/s;->b:Lay0/k;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Ld6/b0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ld6/b0;-><init>(Lky0/s;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
