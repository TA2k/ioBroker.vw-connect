.class public final Lly0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;


# instance fields
.field public final a:Ljava/lang/CharSequence;

.field public final b:I

.field public final c:Lay0/n;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;ILay0/n;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lly0/c;->a:Ljava/lang/CharSequence;

    .line 10
    .line 11
    iput p2, p0, Lly0/c;->b:I

    .line 12
    .line 13
    iput-object p3, p0, Lly0/c;->c:Lay0/n;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lly0/b;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lly0/b;-><init>(Lly0/c;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
