.class public final Lr40/h;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ljava/lang/String;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

.field public i:I


# direct methods
.method public constructor <init>(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lr40/h;->h:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lr40/h;->g:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lr40/h;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lr40/h;->i:I

    .line 9
    .line 10
    sget p1, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->p:I

    .line 11
    .line 12
    iget-object p1, p0, Lr40/h;->h:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-virtual {p1, v0, v0, v0, p0}, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
